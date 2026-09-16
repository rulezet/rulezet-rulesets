rule TTP_XOR_QUAD_CurrentVersionRun_ffbf {
  strings:
    $key_ffbf = { ac d0 [2] 88 de [2] a3 f2 [2] 8d d0 [2] 99 cb [2] 96 d1 [2] 88 cc [2] 8a cd [2] 91 cb [2] 8d cc [2] 91 e3 }

  condition:
    any of them
}