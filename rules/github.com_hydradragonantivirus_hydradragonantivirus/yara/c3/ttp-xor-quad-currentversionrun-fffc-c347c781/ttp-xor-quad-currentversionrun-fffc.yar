rule TTP_XOR_QUAD_CurrentVersionRun_fffc {
  strings:
    $key_fffc = { ac 93 [2] 88 9d [2] a3 b1 [2] 8d 93 [2] 99 88 [2] 96 92 [2] 88 8f [2] 8a 8e [2] 91 88 [2] 8d 8f [2] 91 a0 }

  condition:
    any of them
}