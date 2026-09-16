rule TTP_XOR_QUAD_CurrentVersionRun_ff0d {
  strings:
    $key_ff0d = { ac 62 [2] 88 6c [2] a3 40 [2] 8d 62 [2] 99 79 [2] 96 63 [2] 88 7e [2] 8a 7f [2] 91 79 [2] 8d 7e [2] 91 51 }

  condition:
    any of them
}