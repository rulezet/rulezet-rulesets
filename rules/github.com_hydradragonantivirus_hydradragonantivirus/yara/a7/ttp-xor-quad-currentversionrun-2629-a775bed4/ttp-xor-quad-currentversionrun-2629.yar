rule TTP_XOR_QUAD_CurrentVersionRun_2629 {
  strings:
    $key_2629 = { 75 46 [2] 51 48 [2] 7a 64 [2] 54 46 [2] 40 5d [2] 4f 47 [2] 51 5a [2] 53 5b [2] 48 5d [2] 54 5a [2] 48 75 }

  condition:
    any of them
}