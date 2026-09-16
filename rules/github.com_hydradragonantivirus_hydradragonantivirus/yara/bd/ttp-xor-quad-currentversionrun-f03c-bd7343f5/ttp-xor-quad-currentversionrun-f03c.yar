rule TTP_XOR_QUAD_CurrentVersionRun_f03c {
  strings:
    $key_f03c = { a3 53 [2] 87 5d [2] ac 71 [2] 82 53 [2] 96 48 [2] 99 52 [2] 87 4f [2] 85 4e [2] 9e 48 [2] 82 4f [2] 9e 60 }

  condition:
    any of them
}