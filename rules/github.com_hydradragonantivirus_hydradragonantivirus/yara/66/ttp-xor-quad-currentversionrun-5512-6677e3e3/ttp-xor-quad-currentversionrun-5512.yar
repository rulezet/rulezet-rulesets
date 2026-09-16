rule TTP_XOR_QUAD_CurrentVersionRun_5512 {
  strings:
    $key_5512 = { 06 7d [2] 22 73 [2] 09 5f [2] 27 7d [2] 33 66 [2] 3c 7c [2] 22 61 [2] 20 60 [2] 3b 66 [2] 27 61 [2] 3b 4e }

  condition:
    any of them
}