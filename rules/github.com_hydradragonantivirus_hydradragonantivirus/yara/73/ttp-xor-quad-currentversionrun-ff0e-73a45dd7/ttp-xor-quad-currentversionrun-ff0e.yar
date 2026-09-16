rule TTP_XOR_QUAD_CurrentVersionRun_ff0e {
  strings:
    $key_ff0e = { ac 61 [2] 88 6f [2] a3 43 [2] 8d 61 [2] 99 7a [2] 96 60 [2] 88 7d [2] 8a 7c [2] 91 7a [2] 8d 7d [2] 91 52 }

  condition:
    any of them
}