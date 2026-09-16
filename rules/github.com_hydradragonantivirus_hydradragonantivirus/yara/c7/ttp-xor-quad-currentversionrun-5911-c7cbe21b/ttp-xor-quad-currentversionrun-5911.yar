rule TTP_XOR_QUAD_CurrentVersionRun_5911 {
  strings:
    $key_5911 = { 0a 7e [2] 2e 70 [2] 05 5c [2] 2b 7e [2] 3f 65 [2] 30 7f [2] 2e 62 [2] 2c 63 [2] 37 65 [2] 2b 62 [2] 37 4d }

  condition:
    any of them
}