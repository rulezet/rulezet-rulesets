rule TTP_XOR_QUAD_CurrentVersionRun_3c11 {
  strings:
    $key_3c11 = { 6f 7e [2] 4b 70 [2] 60 5c [2] 4e 7e [2] 5a 65 [2] 55 7f [2] 4b 62 [2] 49 63 [2] 52 65 [2] 4e 62 [2] 52 4d }

  condition:
    any of them
}