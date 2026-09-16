rule TTP_XOR_QUAD_CurrentVersionRun_2909 {
  strings:
    $key_2909 = { 7a 66 [2] 5e 68 [2] 75 44 [2] 5b 66 [2] 4f 7d [2] 40 67 [2] 5e 7a [2] 5c 7b [2] 47 7d [2] 5b 7a [2] 47 55 }

  condition:
    any of them
}