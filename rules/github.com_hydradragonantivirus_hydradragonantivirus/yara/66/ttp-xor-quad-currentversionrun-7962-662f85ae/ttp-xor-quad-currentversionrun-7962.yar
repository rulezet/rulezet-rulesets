rule TTP_XOR_QUAD_CurrentVersionRun_7962 {
  strings:
    $key_7962 = { 2a 0d [2] 0e 03 [2] 25 2f [2] 0b 0d [2] 1f 16 [2] 10 0c [2] 0e 11 [2] 0c 10 [2] 17 16 [2] 0b 11 [2] 17 3e }

  condition:
    any of them
}