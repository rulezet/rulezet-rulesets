rule INFO_MacOS_NamedPipe_ObjC_NSConnection {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for deprecated ObjectiveC interface NSConnection, used in distributed objects mechanism, often to vend an object to other applications"

  strings:
    $ = "NSConnection" ascii wide

  condition:
    any of them
}