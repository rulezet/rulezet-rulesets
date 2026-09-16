rule TTP_XOR_QUAD_CurrentVersionRun_302f {
  strings:
    $key_302f = { 63 40 [2] 47 4e [2] 6c 62 [2] 42 40 [2] 56 5b [2] 59 41 [2] 47 5c [2] 45 5d [2] 5e 5b [2] 42 5c [2] 5e 73 }

  condition:
    any of them
}