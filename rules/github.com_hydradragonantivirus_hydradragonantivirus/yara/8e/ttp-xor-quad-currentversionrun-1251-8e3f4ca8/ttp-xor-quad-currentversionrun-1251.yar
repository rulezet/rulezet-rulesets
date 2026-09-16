rule TTP_XOR_QUAD_CurrentVersionRun_1251 {
  strings:
    $key_1251 = { 41 3e [2] 65 30 [2] 4e 1c [2] 60 3e [2] 74 25 [2] 7b 3f [2] 65 22 [2] 67 23 [2] 7c 25 [2] 60 22 [2] 7c 0d }

  condition:
    any of them
}