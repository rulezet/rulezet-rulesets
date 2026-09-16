rule TTP_XOR_QUAD_CurrentVersionRun_2949 {
  strings:
    $key_2949 = { 7a 26 [2] 5e 28 [2] 75 04 [2] 5b 26 [2] 4f 3d [2] 40 27 [2] 5e 3a [2] 5c 3b [2] 47 3d [2] 5b 3a [2] 47 15 }

  condition:
    any of them
}