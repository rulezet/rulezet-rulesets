rule TTP_XOR_QUAD_CurrentVersionRun_e510 {
  strings:
    $key_e510 = { b6 7f [2] 92 71 [2] b9 5d [2] 97 7f [2] 83 64 [2] 8c 7e [2] 92 63 [2] 90 62 [2] 8b 64 [2] 97 63 [2] 8b 4c }

  condition:
    any of them
}