rule Backdoor_PHP_WPVCD_Deployer {
  meta:
    description = "Deployment script associated with WP-VCD."

  strings:
    $re = /strpos\s*\(\s*\$\w{1,40}\s*,\s*['"]WP_V_CD['"]\s*\)\s*===\s*false/ nocase

  condition:
    $re
}