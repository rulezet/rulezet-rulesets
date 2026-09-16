rule TTP_XOR_QUAD_CurrentVersionRun_ee00 {
  strings:
    $key_ee00 = { bd 6f [2] 99 61 [2] b2 4d [2] 9c 6f [2] 88 74 [2] 87 6e [2] 99 73 [2] 9b 72 [2] 80 74 [2] 9c 73 [2] 80 5c }

  condition:
    any of them
}