rule TTP_XOR_QUAD_CurrentVersionRun_583f {
  strings:
    $key_583f = { 0b 50 [2] 2f 5e [2] 04 72 [2] 2a 50 [2] 3e 4b [2] 31 51 [2] 2f 4c [2] 2d 4d [2] 36 4b [2] 2a 4c [2] 36 63 }

  condition:
    any of them
}