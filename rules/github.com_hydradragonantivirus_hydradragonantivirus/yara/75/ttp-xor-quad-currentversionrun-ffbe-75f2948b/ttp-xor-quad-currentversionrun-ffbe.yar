rule TTP_XOR_QUAD_CurrentVersionRun_ffbe {
  strings:
    $key_ffbe = { ac d1 [2] 88 df [2] a3 f3 [2] 8d d1 [2] 99 ca [2] 96 d0 [2] 88 cd [2] 8a cc [2] 91 ca [2] 8d cd [2] 91 e2 }

  condition:
    any of them
}