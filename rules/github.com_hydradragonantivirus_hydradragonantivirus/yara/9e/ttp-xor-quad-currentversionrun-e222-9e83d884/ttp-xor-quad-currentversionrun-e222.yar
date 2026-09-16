rule TTP_XOR_QUAD_CurrentVersionRun_e222 {
  strings:
    $key_e222 = { b1 4d [2] 95 43 [2] be 6f [2] 90 4d [2] 84 56 [2] 8b 4c [2] 95 51 [2] 97 50 [2] 8c 56 [2] 90 51 [2] 8c 7e }

  condition:
    any of them
}