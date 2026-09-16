rule TTP_XOR_QUAD_CurrentVersionRun_921f {
  strings:
    $key_921f = { c1 70 [2] e5 7e [2] ce 52 [2] e0 70 [2] f4 6b [2] fb 71 [2] e5 6c [2] e7 6d [2] fc 6b [2] e0 6c [2] fc 43 }

  condition:
    any of them
}