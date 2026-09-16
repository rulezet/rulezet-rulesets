rule TTP_XOR_QUAD_CurrentVersionRun_f34c {
  strings:
    $key_f34c = { a0 23 [2] 84 2d [2] af 01 [2] 81 23 [2] 95 38 [2] 9a 22 [2] 84 3f [2] 86 3e [2] 9d 38 [2] 81 3f [2] 9d 10 }

  condition:
    any of them
}