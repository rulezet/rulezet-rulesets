rule TTP_XOR_QUAD_CurrentVersionRun_2902 {
  strings:
    $key_2902 = { 7a 6d [2] 5e 63 [2] 75 4f [2] 5b 6d [2] 4f 76 [2] 40 6c [2] 5e 71 [2] 5c 70 [2] 47 76 [2] 5b 71 [2] 47 5e }

  condition:
    any of them
}