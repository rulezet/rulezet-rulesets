rule inRegPowerSniff: PowerSniff {
  meta:
    copyright = "root9b, LLC"

    authors = "Matt Weeks, Dax Morrow"

    description = "ShellTea + PoSlurp PoS Malware in Registry PowerSniff"

    reference = "https://www.root9b.com/newsroom/shelltea-poslurp-malware"

    version = "1.0"

    last_modified = "2017-06-27"

  strings:
    $hex1 = { 41 2B CF 81 38 BE BA AD AB 48 8B D0 75 09 81 78 04 0D F0 AD 8B }  
  condition:
    $hex1

}