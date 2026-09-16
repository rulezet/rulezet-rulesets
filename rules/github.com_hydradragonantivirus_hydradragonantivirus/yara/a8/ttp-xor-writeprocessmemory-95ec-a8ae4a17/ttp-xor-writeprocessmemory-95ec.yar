rule TTP_XOR_WriteProcessMemory_95ec {
  strings:
    $key_95ec = { c2 9e [2] f0 bc [2] f6 89 [2] d8 89 [2] e7 95 }

  condition:
    any of them
}