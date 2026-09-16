rule INFO_MacOS_NamedPipe_ObjC_NSPipe {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for ObjectiveC interface NSPipe"

  strings:
    $ = "$_NSPipe" ascii wide
    $ = "NSPipe" ascii wide

  condition:
    any of them
}