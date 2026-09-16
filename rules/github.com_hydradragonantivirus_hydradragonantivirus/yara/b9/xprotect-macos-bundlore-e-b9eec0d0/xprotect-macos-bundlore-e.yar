rule XProtect_MACOS_BUNDLORE_E {
  meta:
    description = "MACOS.BUNDLORE.E"

  strings:
    $ = "mmPasswdSuccess"
    $ = "id -un 501"
    $ = "is_root=${isRoot}"
    $ = "client.mm-bq.host"
    $ = "periodikal.com"

  condition:
    4 of them
}