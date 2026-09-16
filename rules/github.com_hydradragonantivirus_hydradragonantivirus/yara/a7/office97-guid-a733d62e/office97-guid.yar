rule office97_guid {
  meta:
    author = "@tylabs"
    ref    = "http://search.lores.eu/fiatlu/GUIDnumber.html"

  strings:
    $a     = "_PID_GUID"
    $magic = { D0 CF 11 E0 }

  condition:
    $magic at 0 and $a
}