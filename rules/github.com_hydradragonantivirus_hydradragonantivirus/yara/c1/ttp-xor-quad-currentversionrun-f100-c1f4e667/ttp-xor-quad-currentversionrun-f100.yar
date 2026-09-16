rule TTP_XOR_QUAD_CurrentVersionRun_f100 {
  strings:
    $key_f100 = { a2 6f [2] 86 61 [2] ad 4d [2] 83 6f [2] 97 74 [2] 98 6e [2] 86 73 [2] 84 72 [2] 9f 74 [2] 83 73 [2] 9f 5c }

  condition:
    any of them
}