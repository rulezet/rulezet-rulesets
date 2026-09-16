rule TTP_XOR_WriteProcessMemory_bf83 {
  strings:
    $key_bf83 = { e8 f1 [2] da d3 [2] dc e6 [2] f2 e6 [2] cd fa }

  condition:
    any of them
}