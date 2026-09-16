rule TTP_XOR_QUAD_CurrentVersionRun_3f35 {
  strings:
    $key_3f35 = { 6c 5a [2] 48 54 [2] 63 78 [2] 4d 5a [2] 59 41 [2] 56 5b [2] 48 46 [2] 4a 47 [2] 51 41 [2] 4d 46 [2] 51 69 }

  condition:
    any of them
}