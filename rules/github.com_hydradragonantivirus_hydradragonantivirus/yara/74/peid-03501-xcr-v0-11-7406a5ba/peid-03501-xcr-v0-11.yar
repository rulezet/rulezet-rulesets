rule PEiD_03501_XCR_v0_11_ {
  meta:
    description = "[XCR v0.11]"
    ep_only     = "true"

  strings:
    $a = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }

  condition:
    $a
}