rule TTP_XOR_QUAD_CurrentVersionRun_3d28 {
  strings:
    $key_3d28 = { 6e 47 [2] 4a 49 [2] 61 65 [2] 4f 47 [2] 5b 5c [2] 54 46 [2] 4a 5b [2] 48 5a [2] 53 5c [2] 4f 5b [2] 53 74 }

  condition:
    any of them
}