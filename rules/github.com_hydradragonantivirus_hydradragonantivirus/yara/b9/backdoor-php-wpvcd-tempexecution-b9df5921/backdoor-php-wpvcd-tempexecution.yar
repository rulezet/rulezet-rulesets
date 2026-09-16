rule Backdoor_PHP_WPVCD_TempExecution {
  meta:
    description = "Backdoor script associated with WP-VCD."

  strings:
    $re = /extract\s*\(\s*wp_temp_setupx?\s*\(\s*\$\w+\s*\)\s*\)/ nocase

  condition:
    $re
}