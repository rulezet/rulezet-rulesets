rule TTP_XOR_QUAD_CurrentVersionRun_f81d {
  strings:
    $key_f81d = { ab 72 [2] 8f 7c [2] a4 50 [2] 8a 72 [2] 9e 69 [2] 91 73 [2] 8f 6e [2] 8d 6f [2] 96 69 [2] 8a 6e [2] 96 41 }

  condition:
    any of them
}