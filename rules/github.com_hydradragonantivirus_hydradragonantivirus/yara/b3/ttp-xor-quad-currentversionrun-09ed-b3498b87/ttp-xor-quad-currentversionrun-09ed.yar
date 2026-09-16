rule TTP_XOR_QUAD_CurrentVersionRun_09ed {
  strings:
    $key_09ed = { 5a 82 [2] 7e 8c [2] 55 a0 [2] 7b 82 [2] 6f 99 [2] 60 83 [2] 7e 9e [2] 7c 9f [2] 67 99 [2] 7b 9e [2] 67 b1 }

  condition:
    any of them
}