rule TTP_XOR_QUAD_CurrentVersionRun_ff0c {
  strings:
    $key_ff0c = { ac 63 [2] 88 6d [2] a3 41 [2] 8d 63 [2] 99 78 [2] 96 62 [2] 88 7f [2] 8a 7e [2] 91 78 [2] 8d 7f [2] 91 50 }

  condition:
    any of them
}