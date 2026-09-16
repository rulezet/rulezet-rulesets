rule TTP_XOR_QUAD_CurrentVersionRun_4511 {
  strings:
    $key_4511 = { 16 7e [2] 32 70 [2] 19 5c [2] 37 7e [2] 23 65 [2] 2c 7f [2] 32 62 [2] 30 63 [2] 2b 65 [2] 37 62 [2] 2b 4d }

  condition:
    any of them
}