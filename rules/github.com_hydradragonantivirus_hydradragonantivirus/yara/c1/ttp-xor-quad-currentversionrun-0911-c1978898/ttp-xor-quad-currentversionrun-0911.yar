rule TTP_XOR_QUAD_CurrentVersionRun_0911 {
  strings:
    $key_0911 = { 5a 7e [2] 7e 70 [2] 55 5c [2] 7b 7e [2] 6f 65 [2] 60 7f [2] 7e 62 [2] 7c 63 [2] 67 65 [2] 7b 62 [2] 67 4d }

  condition:
    any of them
}