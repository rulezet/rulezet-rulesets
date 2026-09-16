rule TTP_XOR_QUAD_CurrentVersionRun_e202 {
  strings:
    $key_e202 = { b1 6d [2] 95 63 [2] be 4f [2] 90 6d [2] 84 76 [2] 8b 6c [2] 95 71 [2] 97 70 [2] 8c 76 [2] 90 71 [2] 8c 5e }

  condition:
    any of them
}