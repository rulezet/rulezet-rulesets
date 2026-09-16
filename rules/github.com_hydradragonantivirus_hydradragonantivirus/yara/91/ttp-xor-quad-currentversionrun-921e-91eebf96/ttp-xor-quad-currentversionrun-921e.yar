rule TTP_XOR_QUAD_CurrentVersionRun_921e {
  strings:
    $key_921e = { c1 71 [2] e5 7f [2] ce 53 [2] e0 71 [2] f4 6a [2] fb 70 [2] e5 6d [2] e7 6c [2] fc 6a [2] e0 6d [2] fc 42 }

  condition:
    any of them
}