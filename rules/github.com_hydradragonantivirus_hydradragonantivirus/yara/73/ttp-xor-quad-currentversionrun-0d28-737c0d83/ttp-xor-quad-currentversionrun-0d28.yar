rule TTP_XOR_QUAD_CurrentVersionRun_0d28 {
  strings:
    $key_0d28 = { 5e 47 [2] 7a 49 [2] 51 65 [2] 7f 47 [2] 6b 5c [2] 64 46 [2] 7a 5b [2] 78 5a [2] 63 5c [2] 7f 5b [2] 63 74 }

  condition:
    any of them
}