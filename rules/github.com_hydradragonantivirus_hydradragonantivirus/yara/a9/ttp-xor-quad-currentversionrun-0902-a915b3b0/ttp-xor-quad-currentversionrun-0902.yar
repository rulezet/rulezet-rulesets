rule TTP_XOR_QUAD_CurrentVersionRun_0902 {
  strings:
    $key_0902 = { 5a 6d [2] 7e 63 [2] 55 4f [2] 7b 6d [2] 6f 76 [2] 60 6c [2] 7e 71 [2] 7c 70 [2] 67 76 [2] 7b 71 [2] 67 5e }

  condition:
    any of them
}