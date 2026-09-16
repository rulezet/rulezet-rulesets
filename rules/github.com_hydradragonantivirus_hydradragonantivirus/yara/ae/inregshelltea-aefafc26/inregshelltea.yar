rule inRegShellTea: ShellTea {
  meta:
    copyright = "root9b, LLC"

    authors = "Matt Weeks, Dax Morrow"

    description = "ShellTea + PoSlurp PoS Malware in Registry ShellTea"

    reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

    version = "1.0"

    last_modified = "2017-06-27"

  strings:
    $hex1 = { 48 83 EC 28 E8 F7 03 00 00 [1015] 48 89 5C 24 18 48 89 4C 24 08 55 56 57 41 54 41 }  
  condition:
    $hex1

}