rule TTP_XOR_QUAD_CurrentVersionRun_f33c {
  strings:
    $key_f33c = { a0 53 [2] 84 5d [2] af 71 [2] 81 53 [2] 95 48 [2] 9a 52 [2] 84 4f [2] 86 4e [2] 9d 48 [2] 81 4f [2] 9d 60 }

  condition:
    any of them
}