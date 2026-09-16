rule APT3102Strings00: APT3102 Family {
  meta:
    description   = "3102 Identifying Strings"
    author        = "Seth Hardy"
    last_modified = "2014-06-25"

  strings:
    $ = "rundll32_exec.dll\x00Update"
    
  condition:
    any of them
}