rule WFYARAGEN_G4399_rules_1 {
  meta:
    description = "Not relying on the typo to detect the backdoor here"

  strings:
    $re = /\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*md5\s*\(\s*__FILE__\s*\)\s*;.*['"]ke['"]\s*\.\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\.\s*['"]ys['"]\s*;.*=\s*['"]use['"]\s*\.\s*\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\.\s*['"]ragents/ nocase

  condition:
    $re
}