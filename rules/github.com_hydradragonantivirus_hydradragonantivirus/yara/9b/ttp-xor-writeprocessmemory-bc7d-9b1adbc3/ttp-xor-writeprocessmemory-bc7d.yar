rule TTP_XOR_WriteProcessMemory_bc7d {
  strings:
    $key_bc7d = { eb 0f [2] d9 2d [2] df 18 [2] f1 18 [2] ce 04 }

  condition:
    any of them
}