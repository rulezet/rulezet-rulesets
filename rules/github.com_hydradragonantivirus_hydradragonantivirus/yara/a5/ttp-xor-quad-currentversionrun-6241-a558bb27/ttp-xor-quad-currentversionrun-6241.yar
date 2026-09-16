rule TTP_XOR_QUAD_CurrentVersionRun_6241 {
  strings:
    $key_6241 = { 31 2e [2] 15 20 [2] 3e 0c [2] 10 2e [2] 04 35 [2] 0b 2f [2] 15 32 [2] 17 33 [2] 0c 35 [2] 10 32 [2] 0c 1d }

  condition:
    any of them
}