rule TTP_XOR_QUAD_CurrentVersionRun_6201 {
  strings:
    $key_6201 = { 31 6e [2] 15 60 [2] 3e 4c [2] 10 6e [2] 04 75 [2] 0b 6f [2] 15 72 [2] 17 73 [2] 0c 75 [2] 10 72 [2] 0c 5d }

  condition:
    any of them
}