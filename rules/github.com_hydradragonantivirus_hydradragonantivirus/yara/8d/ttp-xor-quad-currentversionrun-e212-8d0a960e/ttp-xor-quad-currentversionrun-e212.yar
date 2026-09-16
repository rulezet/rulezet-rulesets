rule TTP_XOR_QUAD_CurrentVersionRun_e212 {
  strings:
    $key_e212 = { b1 7d [2] 95 73 [2] be 5f [2] 90 7d [2] 84 66 [2] 8b 7c [2] 95 61 [2] 97 60 [2] 8c 66 [2] 90 61 [2] 8c 4e }

  condition:
    any of them
}