rule TTP_XOR_QUAD_CurrentVersionRun_ff0a {
  strings:
    $key_ff0a = { ac 65 [2] 88 6b [2] a3 47 [2] 8d 65 [2] 99 7e [2] 96 64 [2] 88 79 [2] 8a 78 [2] 91 7e [2] 8d 79 [2] 91 56 }

  condition:
    any of them
}